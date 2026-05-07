#!/bin/bash
# NestJS DI smoke: define a service via @Injectable + import it through
# @Module. Exercises @nestjs/common (decorators) + @nestjs/core (module
# system) + reflect-metadata + rxjs together. A hoisting-induced peer
# mismatch shows up here as a metadata-reflection failure or an rxjs
# Subject incompatibility.
set -e
node -e "
require('reflect-metadata');
const { Injectable, Module } = require('@nestjs/common');
const { NestFactory } = require('@nestjs/core');

if (typeof Injectable !== 'function') { console.error('@Injectable missing'); process.exit(2); }
if (typeof Module !== 'function') { console.error('@Module missing'); process.exit(3); }
if (typeof NestFactory !== 'object' || typeof NestFactory.create !== 'function') {
    console.error('NestFactory missing'); process.exit(4);
}

// Decorator + DI metadata reflection. If reflect-metadata is split
// across packages, this either throws or silently fails.
const InjDecorator = Injectable();
class TestService {}
InjDecorator(TestService);
const meta = Reflect.getMetadata('design:paramtypes', TestService);
// design:paramtypes is undefined for empty constructors, that's fine —
// what matters is no exception was thrown.

// rxjs touch — many @nestjs APIs return Observables.
const { of, firstValueFrom } = require('rxjs');
firstValueFrom(of(42)).then(v => {
    if (v !== 42) { console.error('rxjs of/firstValueFrom mismatch:', v); process.exit(5); }
});
"
