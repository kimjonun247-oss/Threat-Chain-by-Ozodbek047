import javax.servlet.http.*; import java.sql.*;
public class Safe extends HttpServlet {
  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
    Connection c = DriverManager.getConnection("jdbc:x");
    PreparedStatement s = c.prepareStatement("SELECT * FROM users WHERE name = ?");
    s.setString(1, req.getParameter("name")); s.executeQuery();
  }
}
