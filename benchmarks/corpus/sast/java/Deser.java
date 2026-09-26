import java.io.*; import javax.servlet.http.*;
public class Deser extends HttpServlet {
  protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws Exception {
    ObjectInputStream in = new ObjectInputStream(req.getInputStream());
    Object o = in.readObject();
  }
}
