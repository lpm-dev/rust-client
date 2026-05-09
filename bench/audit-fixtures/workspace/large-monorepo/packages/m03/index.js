"use strict";
const m01 = require("audit-large-m01");
const m02 = require("audit-large-m02");

module.exports = {
	name: "m03",
	info: function () {
		return { name: "m03", chain: ["m03", ...m01.info().chain, ...m02.info().chain] };
	},
};
