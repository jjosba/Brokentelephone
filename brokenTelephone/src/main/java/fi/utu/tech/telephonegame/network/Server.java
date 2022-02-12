package fi.utu.tech.telephonegame.network;
import java.io.*;
import java.net.*;


public class Server extends Thread {
	public static int PORT ;
	public NetworkService networkservice;
	
	public Server(int port, NetworkService net) {
		PORT=port;
		networkservice=net;
	}
	public void run() {
		ServerSocket ss;
		try {
			ss = new ServerSocket(PORT);
			while (true) {
				System.out.println("listening");
				Socket cs = ss.accept();
				System.out.println("connection made :D");
				new Phonehandler(cs, networkservice).start();
					 } 
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

}
