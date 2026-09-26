import javax.servlet.http.*; import java.sql.*;
public class SqlI extends HttpServlet {
  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
    Connection c = DriverManager.getConnection("jdbc:x");
    Statement s = c.createStatement();
    s.executeQuery("SELECT * FROM users WHERE name = '" + req.getParameter("name") + "'");
  }
}
