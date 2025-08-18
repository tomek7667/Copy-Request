const express = require("express");
const fs = require("fs");
const path = require("path");
const multer = require("multer");
const chalk = require("chalk");
const listEndpoints = require("express-list-endpoints");

const app = express();
const port = process.env.PORT || 3001;

// Configure multer for file uploads
const upload = multer({
	dest: "uploads/",
	limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
});

// Middleware
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));
app.use(express.raw({ type: "*/*", limit: "10mb" }));

// Create uploads directory if it doesn't exist
if (!fs.existsSync("uploads")) {
	fs.mkdirSync("uploads");
}

// Request logging middleware
app.use((req, res, next) => {
	const timestamp = new Date().toLocaleTimeString();
	const method = chalk.bold(req.method.padEnd(6));
	const url = chalk.cyan(req.url);
	const ip = chalk.gray(req.ip);

	console.log(
		`\n${chalk.gray("[")}${chalk.yellow(timestamp)}${chalk.gray(
			"]"
		)} ${method} ${url} ${chalk.gray("from")} ${ip}`
	);

	if (Object.keys(req.query).length > 0) {
		console.log(chalk.blue("  Query:"), JSON.stringify(req.query));
	}

	const importantHeaders = [
		"authorization",
		"content-type",
		"user-agent",
		"cookie",
	];
	const filteredHeaders = {};
	importantHeaders.forEach((header) => {
		if (req.headers[header]) {
			filteredHeaders[header] = req.headers[header];
		}
	});

	if (Object.keys(filteredHeaders).length > 0) {
		console.log(chalk.green("  Headers:"), JSON.stringify(filteredHeaders));
	}

	if (req.body) {
		if (Buffer.isBuffer(req.body)) {
			const preview = req.body.toString("utf8").substring(0, 100);
			console.log(
				chalk.magenta("  Body:"),
				`${preview}${req.body.length > 100 ? "..." : ""} ${chalk.gray(
					`(${req.body.length} bytes)`
				)}`
			);
		} else if (
			typeof req.body === "object" &&
			Object.keys(req.body).length > 0
		) {
			console.log(chalk.magenta("  Body:"), JSON.stringify(req.body));
		} else if (typeof req.body === "string" && req.body.length > 0) {
			const preview = req.body.substring(0, 100);
			console.log(
				chalk.magenta("  Body:"),
				`${preview}${req.body.length > 100 ? "..." : ""}`
			);
		}
	}

	next();
});

// Root endpoint - server info
app.get("/", (req, res) => {
	res.json({
		message: "Copy-Request Test Server",
		version: "1.0.0",
		endpoints: {
			"GET /": "Server information",
			"GET /health": "Health check",
			"GET /echo": "Echo query parameters",
			"POST /echo": "Echo request body",
			"PUT /echo": "Echo request body",
			"DELETE /echo": "Echo request body",
			"POST /json": "JSON endpoint",
			"POST /form": "Form data endpoint",
			"POST /upload": "File upload endpoint",
			"GET /delay/:seconds": "Delayed response",
			"GET /status/:code": "Custom status code",
			"GET /headers": "Return request headers",
			"POST /webhook": "Webhook simulator",
			"GET /xml": "XML response",
			"GET /html": "HTML response",
			"GET /binary": "Binary response",
			"GET /content/*": "Various content-type responses",
			"ANY /*": "Catch-all endpoint",
		},
		timestamp: new Date().toISOString(),
	});
});

// Health check
app.get("/health", (req, res) => {
	res.json({ status: "healthy", timestamp: new Date().toISOString() });
});

// Echo endpoints
app.get("/echo", (req, res) => {
	res.json({
		message: "Echo GET request",
		query: req.query,
		headers: req.headers,
		timestamp: new Date().toISOString(),
	});
});

app.post("/echo", (req, res) => {
	res.json({
		message: "Echo POST request",
		body: req.body,
		headers: req.headers,
		contentType: req.get("Content-Type"),
		timestamp: new Date().toISOString(),
	});
});

app.put("/echo", (req, res) => {
	res.json({
		message: "Echo PUT request",
		body: req.body,
		headers: req.headers,
		timestamp: new Date().toISOString(),
	});
});

app.delete("/echo", (req, res) => {
	res.json({
		message: "Echo DELETE request",
		body: req.body,
		headers: req.headers,
		timestamp: new Date().toISOString(),
	});
});

// JSON endpoint
app.post("/json", (req, res) => {
	res.json({
		message: "JSON data received",
		receivedData: req.body,
		dataType: typeof req.body,
		timestamp: new Date().toISOString(),
	});
});

// Form data endpoint
app.post("/form", (req, res) => {
	res.json({
		message: "Form data received",
		formData: req.body,
		contentType: req.get("Content-Type"),
		timestamp: new Date().toISOString(),
	});
});

// File upload endpoint
app.post("/upload", upload.array("files"), (req, res) => {
	const uploadedFiles = req.files
		? req.files.map((file) => ({
				originalName: file.originalname,
				filename: file.filename,
				size: file.size,
				mimetype: file.mimetype,
				path: file.path,
		  }))
		: [];

	res.json({
		message: "Files uploaded successfully",
		files: uploadedFiles,
		formData: req.body,
		timestamp: new Date().toISOString(),
	});
});

// Delayed response
app.get("/delay/:seconds", (req, res) => {
	const seconds = parseInt(req.params.seconds) || 1;
	const delay = Math.min(seconds, 30) * 1000; // Max 30 seconds

	setTimeout(() => {
		res.json({
			message: `Response delayed by ${delay / 1000} seconds`,
			timestamp: new Date().toISOString(),
		});
	}, delay);
});

// Custom status codes
app.get("/status/:code", (req, res) => {
	const statusCode = parseInt(req.params.code) || 200;
	res.status(statusCode).json({
		message: `Custom status code: ${statusCode}`,
		timestamp: new Date().toISOString(),
	});
});

// Headers endpoint
app.get("/headers", (req, res) => {
	res.json({
		message: "Request headers",
		headers: req.headers,
		ip: req.ip,
		timestamp: new Date().toISOString(),
	});
});

// Webhook simulator
app.post("/webhook", (req, res) => {
	console.log(chalk.yellow("🔔 WEBHOOK:"), JSON.stringify(req.body));

	res.json({
		message: "Webhook received successfully",
		received: req.body,
		timestamp: new Date().toISOString(),
	});
});

// XML response
app.get("/xml", (req, res) => {
	res.set("Content-Type", "application/xml");
	res.send(`<?xml version="1.0" encoding="UTF-8"?>
<response>
    <message>XML response from test server</message>
    <timestamp>${new Date().toISOString()}</timestamp>
</response>`);
});

// HTML response
app.get("/html", (req, res) => {
	res.send(`<!DOCTYPE html>
<html>
<head>
    <title>Copy-Request Test Server</title>
</head>
<body>
    <h1>Test Server Response</h1>
    <p>This is an HTML response from the Copy-Request test server.</p>
    <p>Timestamp: ${new Date().toISOString()}</p>
</body>
</html>`);
});

// Binary response
app.get("/binary", (req, res) => {
	const buffer = Buffer.from(
		"This is binary data from the test server",
		"utf8"
	);
	res.set("Content-Type", "application/octet-stream");
	res.send(buffer);
});

// Various content-type responses
app.get("/content/json", (req, res) => {
	res.json({ message: "JSON response", timestamp: new Date().toISOString() });
});

app.get("/content/text", (req, res) => {
	res.set("Content-Type", "text/plain");
	res.send("Plain text response from test server");
});

app.get("/content/csv", (req, res) => {
	res.set("Content-Type", "text/csv");
	res.send("name,age,city\nJohn,30,NYC\nJane,25,LA");
});

app.get("/content/pdf", (req, res) => {
	res.set("Content-Type", "application/pdf");
	// Minimal valid PDF header
	const pdfContent = `%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
>>
endobj
xref
0 4
0000000000 65535 f 
0000000010 00000 n 
0000000079 00000 n 
0000000173 00000 n 
trailer
<<
/Size 4
/Root 1 0 R
>>
startxref
253
%%EOF`;
	res.send(Buffer.from(pdfContent));
});

app.get("/content/image", (req, res) => {
	res.set("Content-Type", "image/png");
	// Minimal valid PNG (1x1 transparent pixel)
	const pngData = Buffer.from([
		0x89,
		0x50,
		0x4e,
		0x47,
		0x0d,
		0x0a,
		0x1a,
		0x0a, // PNG signature
		0x00,
		0x00,
		0x00,
		0x0d, // IHDR chunk length
		0x49,
		0x48,
		0x44,
		0x52, // IHDR
		0x00,
		0x00,
		0x00,
		0x01, // width: 1
		0x00,
		0x00,
		0x00,
		0x01, // height: 1
		0x08,
		0x06,
		0x00,
		0x00,
		0x00, // bit depth, color type, compression, filter, interlace
		0x1f,
		0x15,
		0xc4,
		0x89, // CRC
		0x00,
		0x00,
		0x00,
		0x0a, // IDAT chunk length
		0x49,
		0x44,
		0x41,
		0x54, // IDAT
		0x78,
		0x9c,
		0x63,
		0x00,
		0x01,
		0x00,
		0x00,
		0x05,
		0x00,
		0x01, // compressed data
		0x0d,
		0x0a,
		0x2d,
		0xb4, // CRC
		0x00,
		0x00,
		0x00,
		0x00, // IEND chunk length
		0x49,
		0x45,
		0x4e,
		0x44, // IEND
		0xae,
		0x42,
		0x60,
		0x82, // CRC
	]);
	res.send(pngData);
});

app.get("/content/javascript", (req, res) => {
	res.set("Content-Type", "application/javascript");
	res.send('console.log("Hello from test server");');
});

app.get("/content/css", (req, res) => {
	res.set("Content-Type", "text/css");
	res.send("body { background-color: #f0f0f0; }");
});

app.get("/content/form-urlencoded", (req, res) => {
	res.set("Content-Type", "application/x-www-form-urlencoded");
	res.send("key1=value1&key2=value2&message=test");
});

app.get("/content/multipart", (req, res) => {
	const boundary = "boundary123";
	res.set("Content-Type", `multipart/form-data; boundary=${boundary}`);
	res.send(
		`--${boundary}\r\nContent-Disposition: form-data; name="field1"\r\n\r\nvalue1\r\n--${boundary}--`
	);
});

app.get("/content/yaml", (req, res) => {
	res.set("Content-Type", "application/x-yaml");
	res.send("message: YAML response\ntimestamp: " + new Date().toISOString());
});

app.get("/content/rss", (req, res) => {
	res.set("Content-Type", "application/rss+xml");
	res.send(
		`<?xml version="1.0"?>\n<rss version="2.0">\n<channel>\n<title>Test RSS</title>\n<item><title>Test Item</title></item>\n</channel>\n</rss>`
	);
});

app.get("/content/atom", (req, res) => {
	res.set("Content-Type", "application/atom+xml");
	res.send(
		`<?xml version="1.0"?>\n<feed xmlns="http://www.w3.org/2005/Atom">\n<title>Test Feed</title>\n</feed>`
	);
});

// Authentication simulation
app.get("/auth/basic", (req, res) => {
	const auth = req.get("Authorization");
	if (!auth || !auth.startsWith("Basic ")) {
		res.status(401).json({ message: "Basic authentication required" });
		return;
	}

	const credentials = Buffer.from(auth.slice(6), "base64").toString();
	res.json({
		message: "Basic auth successful",
		credentials: credentials,
		timestamp: new Date().toISOString(),
	});
});

app.get("/auth/bearer", (req, res) => {
	const auth = req.get("Authorization");
	if (!auth || !auth.startsWith("Bearer ")) {
		res.status(401).json({ message: "Bearer token required" });
		return;
	}

	const token = auth.slice(7);
	res.json({
		message: "Bearer auth successful",
		token: token,
		timestamp: new Date().toISOString(),
	});
});

// Cookie handling
app.get("/cookies", (req, res) => {
	res.json({
		message: "Cookies received",
		cookies: req.headers.cookie,
		timestamp: new Date().toISOString(),
	});
});

app.get("/set-cookie", (req, res) => {
	res.cookie("testCookie", "testValue", { maxAge: 900000, httpOnly: true });
	res.json({
		message: "Cookie set",
		timestamp: new Date().toISOString(),
	});
});

// CORS preflight
app.options("*", (req, res) => {
	res.header("Access-Control-Allow-Origin", "*");
	res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
	res.header("Access-Control-Allow-Headers", "*");
	res.sendStatus(200);
});

// CORS headers for all responses
app.use((req, res, next) => {
	res.header("Access-Control-Allow-Origin", "*");
	res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
	res.header("Access-Control-Allow-Headers", "*");
	next();
});

// Catch-all endpoint
app.all("*", (req, res) => {
	res.json({
		message: "Catch-all endpoint - request logged",
		method: req.method,
		url: req.url,
		timestamp: new Date().toISOString(),
	});
});

// Error handling
app.use((err, req, res, next) => {
	console.error("Error:", err.message);
	res.status(500).json({
		error: "Internal server error",
		message: err.message,
		timestamp: new Date().toISOString(),
	});
});

app.listen(port, () => {
	console.log(
		chalk.green.bold(
			`🚀 Copy-Request Test Server running at http://localhost:${port}`
		)
	);
	console.log(chalk.gray("📝 All requests will be logged with details"));

	const routes = listEndpoints(app);
	console.log(chalk.blue.bold("\n🗺️ Available Routes:"));
	routes.forEach((route) => {
		const methods = route.methods.join(", ").padEnd(20);
		console.log(`  ${chalk.yellow(methods)} ${chalk.cyan(route.path)}`);
	});
	console.log("");
});
