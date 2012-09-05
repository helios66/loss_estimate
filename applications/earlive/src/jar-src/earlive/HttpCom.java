package earlive;

import java.io.*;
import java.net.*;

public class HttpCom
{

    public HttpCom()
    {
    }

    public static String send(String url, String msg[][])
    {
        String ret = "";
        try
        {
            URL u = new URL(url);
            URLConnection connection = u.openConnection();
            connection.setDoOutput(true);
            PrintWriter out = new PrintWriter(connection.getOutputStream());
            for(int i = 0; i < msg.length; i++)
                out.print(String.valueOf(msg[i][0]) + "=" + 
                        URLEncoder.encode(msg[i][1], "UTF-8") + (i != msg.length ? "&" : ""));

            out.println();
            out.close();
            BufferedReader in = new BufferedReader(
                    new InputStreamReader(connection.getInputStream()));
            String inputLine;
            while((inputLine = in.readLine()) != null) 
                ret = String.valueOf(ret) + inputLine + "\n";
            in.close();
        }
        catch(Exception e)
        {
            System.out.println(e);
            EarApplet.showError("Error in Http comm", e.toString());
        }
        //System.out.println(ret);
        return ret;
    }
}