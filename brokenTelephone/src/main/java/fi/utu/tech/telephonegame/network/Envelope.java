package fi.utu.tech.telephonegame.network;

import java.io.Serializable;
import java.util.UUID;

/**
 * DO NOT EDIT THIS FILE. - ÄLÄ MUOKKAA TÄTÄ TIEDOSTOA.
 * 
 * This class is used as object to send in the ObjectStreams. 
 * 
 * The idea is to encapsulate the network layer. 
 * 
 * The id value is used to identify the message and can be used to determined 
 * if the message is already received by this node.
 * 
 * The payload variable is used to transport the actual payload object, in our case the Message object.
 * 
 */
 

final class Envelope implements Serializable {

	private static final long serialVersionUID = 1L;
	private final UUID id;
	private Object payload;

	public Envelope(Object payload) {
		this.payload = payload;
		this.id = UUID.randomUUID();
	}

	public Object getPayload() {
		return payload;
	}

	public void setPayload(Object payload) {
		this.payload = payload;
	}

	public UUID getId() {
		return id;
	}

}