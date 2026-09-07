package com.appsecco.dvja.controllers;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class VulnerableDemoController {

    @Autowired
    private DataSource dataSource;

    // VULN: SQL Injection - java/sql-injection
    @RequestMapping(value = "/demo/users/search", method = RequestMethod.GET)
    @ResponseBody
    public String searchUsers(@RequestParam("username") String username) throws SQLException {
        String sql = "SELECT * FROM users WHERE login = '" + username + "'";
        try (Connection connection = dataSource.getConnection();
             Statement statement = connection.createStatement();
             ResultSet results = statement.executeQuery(sql)) {
            StringBuilder body = new StringBuilder();
            while (results.next()) {
                body.append(results.getString("login")).append('\n');
            }
            return body.toString();
        }
    }

    // VULN: Reflected Cross-Site Scripting - java/xss
    @RequestMapping(value = "/demo/greet", method = RequestMethod.GET)
    public void greet(@RequestParam("name") String name, HttpServletResponse response)
            throws IOException {
        response.setContentType("text/html");
        response.getWriter().println("<h1>Hello, " + name + "</h1>");
    }

    // VULN: Code Injection - java/script-injection
    @RequestMapping(value = "/demo/calculate", method = RequestMethod.GET)
    @ResponseBody
    public String calculate(@RequestParam("expression") String expression) throws ScriptException {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("JavaScript");
        Object result = engine.eval(expression);
        return String.valueOf(result);
    }

    // VULN: Path Traversal - java/path-injection
    @RequestMapping(value = "/demo/files/read", method = RequestMethod.GET)
    @ResponseBody
    public String readFile(@RequestParam("filename") String filename) throws IOException {
        File file = new File("/var/data/uploads/" + filename);
        byte[] content = Files.readAllBytes(file.toPath());
        return new String(content, StandardCharsets.UTF_8);
    }

    // VULN: Server-Side Request Forgery - java/ssrf
    @RequestMapping(value = "/demo/fetch", method = RequestMethod.GET)
    @ResponseBody
    public String fetch(@RequestParam("url") String url) throws IOException {
        URL target = new URL(url);
        HttpURLConnection connection = (HttpURLConnection) target.openConnection();
        try (InputStream input = connection.getInputStream();
             ByteArrayOutputStream body = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = input.read(buffer)) != -1) {
                body.write(buffer, 0, bytesRead);
            }
            return body.toString("UTF-8");
        } finally {
            connection.disconnect();
        }
    }
}