// Example generated code - modify URL to point to test server
const constructUrl = ({ parameters, path, protocol, domain, port }) => {
	const urlSearchParams = new URLSearchParams();
	for (const key in parameters) {
		urlSearchParams.set(key, parameters[key]);
	}
	const parametersStr = urlSearchParams.toString();
	return parametersStr === ""
		? `${protocol}://${domain}:${port}${path}`
		: `${protocol}://${domain}:${port}${path}?${parametersStr}`;
};

const request_1 = async (
	urlObject,
	method,
	headers,
	cookies,
	authorization,
	body,
	files,
	commonHeaders
) => {
	const url = constructUrl(urlObject);
	const response = await fetch(url, {
		method,
		headers: { ...commonHeaders, ...headers },
	});
	return await response.text();
};

const main = async () => {
	const commonHeaders = {};
	const method_1 = "GET";
	const headers_1 = { "User-Agent": "Copy-Request-Test" };
	const url_1 = {
		parameters: { test: "true" },
		path: "/api/test",
		protocol: "http",
		domain: "localhost",
		port: 3001,
	};
	const result = await request_1(
		url_1,
		method_1,
		headers_1,
		undefined,
		undefined,
		undefined,
		undefined,
		commonHeaders
	);
	console.log("Response:", result);
};

main();
