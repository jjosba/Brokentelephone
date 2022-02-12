package fi.utu.tech.telephonegame.network;

import java.io.*;
import java.net.*;
import java.util.UUID;
import java.util.concurrent.TransferQueue;

public class Phonehandler extends Thread {
	private Socket client;
	public NetworkService networkservice;
	private ObjectOutputStream oOut;
	
	

	public Phonehandler(Socket s, NetworkService net) {
		client = s;
		networkservice = net;
		networkservice.setAsiakkaat(this);
	}
	
	public Phonehandler( NetworkService net) {
		networkservice = net;
		networkservice.setAsiakkaat(this);
	}
	
public void connect(String clientIP, int clientPort) {
	try{
		client = new Socket(clientIP, clientPort);
	 
	} catch (IOException e) {
		System.out.println(e.getMessage());
	}
}

	// ota viestit pois envelopesta ja laita ne jonoon--> laita viestit outQueue;hin
	
	public void send(Envelope e) {
		try {
			oOut.writeObject(e);
			oOut.flush();
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
	}

	public void run() {

		try {
			System.out.println("Spawning thread ...");
			InputStream iS = client.getInputStream();
			OutputStream oS = client.getOutputStream();
			oOut = new ObjectOutputStream(oS);
			ObjectInputStream oIn = new ObjectInputStream(iS);

			while (true)
				try {
					while (true) {
						Object o = oIn.readObject();

						if (o instanceof Envelope) {
							Envelope e = (Envelope) o;
							Object m = e.getPayload();
							networkservice.addoutQueue(m);
						}
					}
				} catch (ClassNotFoundException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
