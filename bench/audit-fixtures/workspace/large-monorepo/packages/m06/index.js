"use strict";
const m02 = require("audit-large-m02");
const m05 = require("audit-large-m05");

module.exports = {
	name: "m06",
	info: function () {
		return { name: "m06", chain: ["m06", ...m02.info().chain, ...m05.info().chain] };
	},
};
