import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Servlet implementation class internetProtocol
 */
@WebServlet("/protocol")
public class internetProtocol extends HttpServlet {

	protected void doGet(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		// TODO Auto-generated method stub
		request.setCharacterEncoding("utf-8");
		response.setContentType("text/html;charset=utf-8");
		PrintWriter out = response.getWriter();
		String content = request.getParameter("value");
		Protocol p = new Protocol();
		String result = "";
		result = p.ethernet(content);
		String re = request.getParameter("v");

		out.print("<!DOCTYPE HTML>");
		out.print("<html>");
		out.print("<head>");
		out.print("<title>Protocol</title>");
		out.print("<meta charset='utf-8' />");
		out.print("<meta name='viewport'");
		out.print("	content='width=device-width, initial-scale=1, user-scalable=no' />");
		out.print("<link rel='stylesheet' href='./assets/css/main.css' />");
		out.print("</head>");
		out.print("<body class='is-preload' style='background:#F5ECCE'>");
		out.print("	<!-- Wrapper -->");
		out.print("	<div id='wrapper'>");
		out.print("	<!-- Main -->");
		out.print("<div id='main'>");
		out.print("<div class='inner'>");
		out.print("<!-- Content -->");
		out.print("<section>");
		out.print("<header class='main'>");
		out.print("<h1>Protocol</h1>");
		out.print("</header>");
		out.print("<br>");
		out.print("<h2>Result</h2>");
		out.print("<div class='row gtr-uniform'>");
		out.print("<div class='col-12'>");
		out.print("<pre placeholder='Enter your message' rows='6'>");
		out.print("<code style='background:#F2F2F2'>" + result + "</code>");
		out.print("</pre>");
		out.print("</div>");

		out.print("	<div class='row gtr-uniform'>");
		out.print("	<div class='col-12'>");
		out.print("	<ul class='actions'>");
		out.print("	<li><input type='submit' value='retry' class='primary' onClick='history.go(-1)' /></li>");
		out.print("	</ul>");
		out.print("	</div>");
		out.print("	</div>");

		out.print("<!-- Scripts -->");
		out.print("<script src='./assets/js/jquery.min.js'></script>");
		out.print("<script src='./assets/js/browser.min.js'></script>");
		out.print("<script src='./assets/js/breakpoints.min.js'></script>");
		out.print("<script src='./assets/js/util.js'></script>");
		out.print("<script src='./assets/js/main.js'></script>");
		out.print("</body>");
		out.print("</html>");

	}

}