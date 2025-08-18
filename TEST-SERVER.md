# Test Server

Quick server to test your generated JavaScript requests.

## Setup

```bash
npm install
npm start
```

Server runs on `http://localhost:3001` and shows all available routes on startup.

## Usage

1. Generate JS code with Copy-Request extension
2. Change the URL in your code to `localhost:3001/whatever`
3. Run your code
4. Check the server console - it logs everything nicely with colors

## What you get

**Clean logs** - Only shows the important stuff (method, URL, key headers, body preview)

**Tons of endpoints** - The server lists all routes when it starts, but here are the useful ones:
- `/echo` - Echoes back whatever you send
- `/json` - For JSON requests  
- `/form` - For form data
- `/upload` - For file uploads
- `/content/*` - Different response types (json, xml, pdf, etc.)
- `/auth/*` - Test authentication
- `/delay/5` - Slow responses
- `/status/404` - Custom status codes

**Real responses** - Not fake data. The PDF endpoint returns actual PDF bytes, PNG returns real PNG data, etc.

## Examples

Change your generated code URLs like this:

```javascript
// Instead of: https://example.com/api/login
// Use: http://localhost:3001/json

// Instead of: https://api.site.com/upload  
// Use: http://localhost:3001/upload
```

That's it. The server handles everything and logs it cleanly.