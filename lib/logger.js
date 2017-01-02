module.exports = function makeLogger(module, auth) {
	if (!module) { module = "DEFAULT"; }
	return {
		i: function(msg) {
			logFn.apply({ module: module, type: "I", auth: auth }, arguments);
		},
		w: function(msg) {
			logFn.apply({ module: module, type: "W", auth: auth }, arguments);
		},
		e: function(msg) {
			logFn.apply({ module: module, type: "E", auth: auth }, arguments);
		},
		z: function(msg) {
			logFn.apply({ module: module, type: "Z", auth: auth }, arguments);
		},
		auth: function(new_auth) {
			return makeLogger(module, new_auth);
		}
	};
};

function logFn(message) {
	var msg = {
		"@timestamp": Date.now(),
		fields: {
			type: this.type,
			name: this.module
		}
	};

	if (this.auth) {
		msg.auth = this.auth;
	}

	if (this.type === 'Z') {
		msg.data = message;
	} else {
		var msg_parts = [];
		for (var idx in arguments) {
			var parameter = arguments[idx];
			if (typeof parameter === "string") {
				msg_parts.push(parameter);
			} else if (parameter instanceof Error) {
				msg_parts.push(parameter.stack);
			} else {
				msg_parts.push(JSON.stringify(parameter));
			}
		}
		msg.message = msg_parts.join(' ');
	}

	// console.log(msg);
	console.log(JSON.stringify(msg));
}