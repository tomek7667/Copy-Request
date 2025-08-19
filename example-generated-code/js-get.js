const fs = require("fs");

const constructUrl = ({ parameters, path, protocol, domain, port }) => {
	const urlSearchParams = new URLSearchParams();
	for (const key in parameters) {
		const value = parameters[key];
		urlSearchParams.set(key, value);
	}
	const parametersStr = urlSearchParams.toString();
	if (parametersStr === "") {
		return `${protocol}://${domain}:${port}${path}`;
	} else {
		return `${protocol}://${domain}:${port}${path}?${parametersStr}`;
	}
};

const constructCookies = (cookieObject) => {
	const cookiesArr = [];
	for (const cookieName in cookieObject) {
		const cookieValue = cookieObject[cookieName];
		cookiesArr.push(`${cookieName}=${cookieValue}`);
	}
	const stringifiedCookies = cookiesArr.join("; ");
	return stringifiedCookies;
};

const constructXWwwFormUrlencoded = (bodyObject) => {
	const formBody = [];
	for (const property in bodyObject) {
		const encodedKey = encodeURIComponent(property);
		const encodedValue = encodeURIComponent(bodyObject[property]);
		const joined = `${encodedKey}=${encodedValue}`;
		formBody.push(joined);
	}
	const stringifiedBody = formBody.join("&");
	return stringifiedBody;
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
		headers: {
			...commonHeaders,
			...headers,
		},
	});
	// const data = await response.json();
	const data = await response.text();
	return data;
};

const main = async () => {
	const commonHeaders = {
		"Sec-Ch-Ua": '"Not)A;Brand";v="8", "Chromium";v="138"',
		"Sec-Ch-Ua-Platform": '"macOS"',
		"Sec-Ch-Ua-Mobile": "?0",
	};
	// const wordlist = fs.readFilesync("rockyou.txt", "utf-8").split("\n")
	// const len = wordlist.length;
	// for (let i = 0; i < len; i++) {
	const method_1 = "GET";
	const headers_1 = {};
	const url_1 = {
		path: "/",
		protocol: "https",
		port: 443,
		domain: "example.com",
		parameters: {},
	};
	await request_1(
		url_1,
		method_1,
		headers_1,
		undefined,
		undefined,
		undefined,
		undefined,
		commonHeaders
	);
	// }
};

(async () => {
	await main();
})();
