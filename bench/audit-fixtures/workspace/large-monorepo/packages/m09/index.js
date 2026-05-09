"use strict";
const m08 = require("audit-large-m08");
const m06 = require("audit-large-m06");

module.exports = {
	name: "m09",
	info: function () {
		return { name: "m09", chain: ["m09", ...m08.info().chain, ...m06.info().chain] };
	},
};
