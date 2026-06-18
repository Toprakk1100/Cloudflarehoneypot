export default {
  async fetch(request, env) {
    const cf = request.cf || {};
    const url = new URL(request.url);

    let body = "";
    try {
      body = await request.text();
    } catch {}

    if (url.pathname === "/logs") {
      const key = url.searchParams.get("key");
      if (key !== env.VIEWER_KEY) {
        return Response.json({ error: "Unauthorized" }, { status: 401 });
      }
      const { results } = await env.DB.prepare(
        "SELECT * FROM hits ORDER BY timestamp DESC LIMIT 100"
      ).all();
      return Response.json(results);
    }

    await env.DB.prepare(`
      INSERT INTO hits (timestamp, ip, asn, country, user_agent, method, path, headers, body, cf_threat_score, cf_bot_score)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      new Date().toISOString(),
      cf.ip || request.headers.get("cf-connecting-ip") || "unknown",
      cf.asn || null,
      cf.country || null,
      request.headers.get("user-agent") || null,
      request.method,
      url.pathname,
      JSON.stringify(Object.fromEntries(request.headers)),
      body,
      cf.threatScore || null,
      cf.botManagement?.score || null,
    ).run();

    if (url.pathname === "/api/v1/login") {
      return Response.json({ error: "Invalid credentials" }, { status: 401 });
    } else if (url.pathname === "/admin") {
      return Response.json({ error: "Forbidden" }, { status: 403 });
    } else if (url.pathname === "/health") {
      return Response.json({ status: "ok" });
    } else {
      return Response.json({ error: "Not found" }, { status: 404 });
    }
  }
};
