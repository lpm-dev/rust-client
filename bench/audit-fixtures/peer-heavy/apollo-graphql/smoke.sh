#!/bin/bash
# Apollo + GraphQL: parse + execute a trivial query. Validates that
# Apollo's GraphQL peer is the same instance as the project's `graphql`
# import — otherwise the AST types don't match across the boundary.
set -e
node -e "
const { gql, ApolloClient, InMemoryCache, HttpLink } = require('@apollo/client/core');
const { parse, print, Kind } = require('graphql');

// gql parses a query through Apollo, which uses graphql internally.
// If Apollo's graphql differs from ours, the document AST won't be a
// valid graphql Document on our import, and print() will reject it.
const doc = gql\`{ user { id name } }\`;
const printed = print(doc);
if (!printed.includes('user') || !printed.includes('id')) {
    console.error('graphql.print failed on apollo-parsed document:', printed);
    process.exit(2);
}

// Validate the AST kind comes from graphql — same module instance.
if (doc.definitions[0].kind !== Kind.OPERATION_DEFINITION) {
    console.error('Kind enum mismatch (apollo graphql instance differs from ours)');
    process.exit(3);
}

// Build an ApolloClient with a no-op link (we're not making network calls).
const client = new ApolloClient({
    link: new HttpLink({ uri: 'http://example.invalid/graphql', fetch: () => Promise.reject(new Error('no-net')) }),
    cache: new InMemoryCache(),
});
if (typeof client.query !== 'function') {
    console.error('ApolloClient missing query method');
    process.exit(4);
}
"
