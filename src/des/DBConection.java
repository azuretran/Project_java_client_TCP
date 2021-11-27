/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package des;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import sun.security.krb5.internal.KDCOptions;

/**
 *
 * @author azure Tran
 */
public class DBConection {

    public static Connection getConnection() {
        Connection connection = null;
        try {
            Class.forName("com.microsoft.sqlserver.jdbc.SQLServerDriver");
            String url = "jdbc:sqlserver://localhost:1433; databaseName=MC";
            String user = "sa";
            String pass = "123456";
            connection = DriverManager.getConnection(url, user, pass);

        } catch (Exception ex) {
            ex.printStackTrace();

        }
        return connection;
    }

    public static void closeConnection(Connection con) {
        if (con != null) {

            try {
                con.close();
            } catch (Exception e) {
            }

        }

    }

    public static void main(String[] args) {

    }
}
