"use strict";
const m01 = require("audit-large-m01");
const m04 = require("audit-large-m04");

module.exports = {
	name: "m07",
	info: function () {
		return { name: "m07", chain: ["m07", ...m01.info().chain, ...m04.info().chain] };
	},
};
