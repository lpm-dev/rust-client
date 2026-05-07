"use strict";
const utility = require("audit-utility");
const _ = require("lodash");

module.exports = {
	greetUpper: function (name) {
		// Tests both internal (workspace:*) and external (^4.17.21) resolution.
		return _.toUpper(utility.greeting(name));
	},
};
