'use strict';

var kapujs = require('kapujs');
var network = kapujs.networks.kapu;
var ed = {};

ed.makeKeypair = function (seed) {
	return kapujs.crypto.getKeys(seed);
};

ed.sign = function (hash, keypair) {
	return keypair.sign(hash).toDER().toString("hex");
};

ed.verify = function (hash, signatureBuffer, publicKeyBuffer) {
	try {
		var ecsignature = kapujs.ECSignature.fromDER(signatureBuffer);
		var ecpair = kapujs.ECPair.fromPublicKeyBuffer(publicKeyBuffer, network);
		return ecpair.verify(hash, ecsignature);
	} catch (error){
		return false;
	}
};

module.exports = ed;
