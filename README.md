Some helper functions for working with the Node http module

I wrote these because:

1. Writing code that uses the Node built-in http module directly is a bit tedious
2. I was repulsed by the size and complexity of popular modules like [request] (https://github.com/request/request)

This module is not trying to compete with [request] (https://github.com/request/request) - it only provides a few very simple functions to help reduce `boilerplate` when using the http module