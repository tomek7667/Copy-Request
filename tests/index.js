const express = require("express");

const app = express();
const port = Number(process.env.PORT ?? 3000);

// Simple GET /
app.get("/simple", (req, res) => {
    res.send(`
<html>
    <head>
        <title>Simple test</title>
    </head>
    <body>
        <h1>Example Simple Get retrieval</h1>
        <h2>Subtitle of the simple request</h2>
        <p>Paragraph content lorem ipsum</p>
    </body>
</html>
`);
})

// GET with Query parameters
app.get("/query", (req, res) => {
    const { query } = req;
    res.send(`
<html>
    <head>
        <title>Query test</title>
    </head>
    <body>
        <h1>Example Query Get retrieval</h1>
        <h2>Subtitle of the simple request</h2>
        <p>${JSON.stringify(query)}</p>
    </body>
</html>
`);
})

app.listen(port, () => {
    console.log(`Test app is listening on http://127.0.0.1:${port}`);
});

