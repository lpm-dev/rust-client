"use strict";
const core = require("audit-core");
const utility = require("audit-utility");

module.exports = {
	run: function () {
		// Exercises the full chain: consumer → core → utility, plus
		// consumer → utility directly. Both internal deps must resolve;
		// failure here is workspace resolution / hoisting bug.
		return {
			direct: utility.greeting("consumer"),
			throughCore: core.greetUpper("world"),
		};
	},
};
