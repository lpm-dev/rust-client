"use strict";
const m09 = require("audit-large-m09");
const m03 = require("audit-large-m03");

module.exports = {
	name: "m10",
	info: function () {
		return { name: "m10", chain: ["m10", ...m09.info().chain, ...m03.info().chain] };
	},
};
