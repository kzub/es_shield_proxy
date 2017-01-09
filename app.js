var express = require('express');
var http = require('http');
var logger = require('./lib/logger')("ES_PROXY");
var log = logger;
var config = require('./config');
var userServiceWindow = {};

const termsForbiddenFields = config.limits.termsForbiddenFields;
const termsMaxSize = config.limits.termsMaxSize;
const searchMaxRange = config.limits.searchMaxRange;
const searchMaxFacets = config.limits.searchMaxFacets;
const searchMaxRPS = config.limits.searchMaxRPS;

var app = express();
log.i('Proxy server starting...');
app.use(express.compress());
app.use(proxyRequest);
run();

function run() {
  http.createServer(app).listen(config.proxy.listen_port);
  log.i('Proxy server listening on ' + config.proxy.listen_port);
}

function proxyRequest(request, response) {
  var log = logger.auth(request.headers.ottuser);

  var buf_size = 1024;
  var buf_used = 0;
  var buf = new Buffer(buf_size);

  request.addListener('data', function doitagain(chunk) {
    if (buf_size - buf_used < chunk.length) {
      buf_size *= 2;
      var new_buf = new Buffer(buf_size);
      buf.copy(new_buf, 0, 0, buf_used);
      buf = new_buf;
      doitagain(chunk);
      return;
    }

    chunk.copy(buf, buf_used);
    buf_used += chunk.length;
  });

  request.addListener('end', function() {
    var body = buf.slice(0, buf_used).toString();
    var access = checkUserPermissions(request, body);

    if (access.granted) {
      processUserRequest(request, response, buf, body, access.delayProcessing);
    } else {
      var result = { 
        event: 'RQ_DECLINED',
        error: true,
        reason: access.reason,
        request: request.url,
        request_body: body,
        request_size: body.length || undefined
      };
      response.status(403).send(result);
      log.z(result);
    }
  });
}

function processUserRequest(request, response, buf, body, delay, wasDelayed) {
  var log = logger.auth(request.headers.ottuser);

  if (isFinite(delay) && delay > 0) {
    setTimeout(function() {
      processUserRequest(request, response, buf, body, undefined, delay);
    }, delay);
    log.z({
      event: 'RQ_DELAY',
      request: request.url,
      request_delay: delay,
      request_size: body.length || undefined,
      request_body: body
    });
    return;
  }

  var options = {
    path: request.url,
    method: request.method,
    hostname: config.elastic.host,
    port: config.elastic.port,
    headers: request.headers
  };

  var proxyReq = http.request(options);
  var startTime = Date.now();

  proxyReq.addListener('error', function(err){
    var result = {
        event: 'RQ_ERROR',
        error: true,
        reason: err.code,
        response_time: Date.now() - startTime,
        request: request.url,
        request_delay: wasDelayed,
        request_size: body.length || undefined,
        request_body: body
    };
    response.status(500).send(result);
    log.z(result);
  });

  proxyReq.addListener('response', function(proxyResp) {
    response.writeHead(proxyResp.statusCode, proxyResp.headers);
    var responseLength = 0;
    proxyResp.addListener('data', function(chunk) {
      responseLength += chunk.length;
      response.write(chunk, 'binary');
    });

    proxyResp.addListener('end', function() {
      log.z({
        event: 'RQ_END',
        request: request.url,
        request_delay: wasDelayed,
        request_size: body.length || undefined,
        response_time: Date.now() - startTime,
        response_size: responseLength,
        request_body: body
      });
      response.end();
    });
  });

  proxyReq.end(buf, 'binary');
}

function checkUserPermissions(request, buf) {
  if (request.url.indexOf('search') === -1) {
    return makePermisionResponse(true);
  }

  var username = request.headers.ottuser;
  if (!username) {
    return makePermisionResponse(false, 'no user auth');
  }

  var data = parserRequestBody(buf);
  if (!data) {
    return makePermisionResponse(false, 'request parsing error');
  }

  var searchRange = getMaxSearchRange(data);
  if (searchRange > searchMaxRange) {
    return makePermisionResponse(false, 'search interval range exceed limit: ' + searchMaxRange);
  }

  var facetsCount = getFacetsCount(data);
  if (facetsCount && facetsCount > searchMaxFacets) {
    return makePermisionResponse(false, 'facets count exceed maximum: ' + searchMaxFacets);
  }

  if (facetsCount && searchRange) {
    var facetsRangeFactor = (searchMaxRange/searchRange).toFixed(2);
    if (facetsCount > facetsRangeFactor) {
      return makePermisionResponse(false, 'facets count/search factor exceed maximum: ' + 
                                  [facetsCount, facetsRangeFactor, 
                                  searchMaxRange, searchRange].join(':')); 
   }
  }

  var badTerms = isTermsBad(data);
  if (badTerms) {
    return makePermisionResponse(false, badTerms);
  }

  var delay = getUserDelay(username, searchRange, facetsCount); 
  return makePermisionResponse(true, 'OK', { delayProcessing: delay });
}

function isTermsBad(data) {
  try {
    for (var key in data.facets) {
      var facet = data.facets[key];
      var term_field = undefined;
      var term_size = 0;
      if (facet.terms) {
        term_field = facet.terms.field;
        term_size = facet.terms.size;
      }
      else if (facet.terms_stats) {
        term_field = facet.terms_stats.key_field;
        term_size = facet.terms_stats.size;
      }
      if (term_field) {
        term_field = term_field.replace(/\.raw/, '');
        if (termsForbiddenFields.indexOf(term_field) > -1) {
          return 'use term is forbidden for field: ' + term_field;
        }
        if (term_size > termsMaxSize) {
          return 'max term size is: ' + termsMaxSize;
        }
      }
    }
  } catch (e) {
    log.e('checkTerm', e);
  }
}

function getFacetsCount(data) {
  try {
    if (!data || !data.facets) {
      return;
    }
    return Object.keys(data.facets).length;
  } catch (e) {
    log.e('getFacetsCount', e, data.facets);
  }
  return;
}

function getMaxSearchRange(data) {
  var ranges = [];
  try {
    var processMust = function(must) {
      for (var rId in must) {
        var element = must[rId];
        if (element.range && element.range["@timestamp"]){
          var from = element.range["@timestamp"].from;
          var to = element.range["@timestamp"].to;
          ranges.push(Math.round((to - from)/1000));
        }
      }
    };

    for (var key in data.facets) {
      var facet = data.facets[key];
      if (facet.facet_filter &&
          facet.facet_filter.fquery &&
          facet.facet_filter.fquery.query &&
          facet.facet_filter.fquery.query.filtered &&
          facet.facet_filter.fquery.query.filtered.filter &&
          facet.facet_filter.fquery.query.filtered.filter.bool &&
          facet.facet_filter.fquery.query.filtered.filter.bool.must) {
        processMust(facet.facet_filter.fquery.query.filtered.filter.bool.must);
      }

      if (facet.query &&
          facet.query.filtered &&
          facet.query.filtered.filter &&
          facet.query.filtered.filter.bool &&
          facet.query.filtered.filter.bool.must) {
        processMust(facet.query.filtered.filter.bool.must);
      }
    }

    if (data.query &&
        data.query.filtered &&
        data.query.filtered.filter &&
        data.query.filtered.filter.bool &&
        data.query.filtered.filter.bool.must) {
      processMust(data.query.filtered.filter.bool.must);
    }
    // return max value
    ranges.sort(function(a, b){ return b - a; });
  } catch(e) {
    log.e('getMaxSearchRange', e);
  }
  return ranges[0];
}

function parserRequestBody(buf) {
  try {
    return JSON.parse(buf);
  } catch(e) {
    log.e('parserRequestBody', 'Data parsing error:', e);
    return;
  }
}

function makePermisionResponse(granted, reason, properties) {
  var result = {
    granted: granted,
    reason: reason
  };
  if (properties) {
    for (var id in properties) {
      result[id] = properties[id];
    }
  }
  return result;
}

function getUserDelay(username, searchRange, facetsCount) {
  var timeframe = 1000/searchMaxRPS; // requests per second
  if (isFinite(searchRange)){
    var kSearch = (0.5 + searchRange/(60*60*24)); // search difficulty multiplier
    if (kSearch > 11) { kSearch = 11; }
    if (kSearch > 1) { timeframe *= kSearch; }    
  }
  if (isFinite(facetsCount)) {
    var kFacets = (0.75 + facetsCount/4); // queries per search request multiplier
    if (kFacets > 11) { kFacets = 11; }
    if (kFacets > 1) { timeframe *= kFacets; }    
  }

  if (!userServiceWindow[username] || userServiceWindow[username] < Date.now()) {
    userServiceWindow[username] = Date.now() + timeframe;
    return;
  }

  userServiceWindow[username] += timeframe;
  return Math.round(userServiceWindow[username] - Date.now());
}

