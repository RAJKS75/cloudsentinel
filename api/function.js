{
  "bindings": [
    {
      "type": "httpTrigger",
      "authLevel": "function",
      "methods": ["GET", "POST", "PUT", "DELETE"],
      "route": "{*path}",
      "name": "req"
    }
  ],
  "scriptFile": "index.js"
}