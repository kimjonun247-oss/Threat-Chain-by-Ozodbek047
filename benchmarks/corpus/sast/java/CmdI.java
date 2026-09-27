import javax.servlet.http.*;
public class CmdI extends HttpServlet {
  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
    Runtime.getRuntime().exec("ping " + req.getParameter("host"));
  }
}
