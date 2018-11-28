package us.categorize.naive.users.server;

import java.util.UUID;

import javax.ws.rs.Consumes;
import javax.ws.rs.CookieParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.NewCookie;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;

import us.categorize.Configuration;
import us.categorize.api.UserStore;
import us.categorize.model.User;

@Path("/auth")
public class Auth {
	protected UserStore userStore;
	
	public Auth() {
		this.userStore = Configuration.instance().getUserStore();
	}
	
	@POST
	@Path("/login")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response login(User user, @CookieParam("categorizeus") Cookie cookie) {
		String cookieValue = cookie==null?UUID.randomUUID().toString():cookie.getValue();
		boolean validUser = userStore.establishUserSession(user, cookieValue);
		if(!validUser) {
			return Response.noContent().status(401).build();
		}
		ResponseBuilder response = Response.noContent().status(200);
		if(cookie==null) {
			response.cookie(new NewCookie("categorizeus", cookieValue));
		}
		return response.build();
	}
	
	@POST
	@Path("/logout")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response logout(User user, @CookieParam("categorizeus") Cookie cookie) {
		ResponseBuilder response = Response.noContent().status(200);
		if(cookie!=null) {
			userStore.destroySessionUser(cookie.getValue());
			NewCookie deletedCookie = new NewCookie(cookie, "logout", 0, false);
			response.cookie(deletedCookie);
		}
		return response.build();
	
	}
}
