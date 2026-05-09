"use strict";
const m07 = require("audit-large-m07");
const m05 = require("audit-large-m05");

module.exports = {
	name: "m08",
	info: function () {
		return { name: "m08", chain: ["m08", ...m07.info().chain, ...m05.info().chain] };
	},
};
