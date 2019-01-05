package us.categorize.naive.users.server;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.util.UUID;

import javax.ws.rs.Consumes;
import javax.ws.rs.CookieParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
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
	private String googleClientId, googleClientSecret;
	
	public Auth() {
		this.userStore = Configuration.instance().getUserStore();
		googleClientId = Configuration.instance().getGoogleClientId();
		googleClientSecret = Configuration.instance().getGoogleClientSecret();
	}
	
	@GET
	@Path("/oauthcb")
	public Response handleGoogleLogin(@CookieParam("categorizeus") Cookie cookie, 
			@QueryParam("code") String code,
			@QueryParam("error") String error) {
		System.out.println("Error " + error);
		System.out.println("Code " + code);
		try {
			return Response.seeOther(new URI("http://localhost:8080")).build();
		} catch (URISyntaxException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return Response.serverError().build();
	}
	@GET
	@Path("/oauth/google")
	public Response sendGoogleRedirect(@CookieParam("categorizeus") Cookie cookie) {
		String authURIPattern = "https://accounts.google.com/o/oauth2/v2/auth?" + 
				"scope=%s&" + 
				"access_type=offline&" + 
				"include_granted_scopes=true&" + 
				"state=state_parameter_passthrough_value&" + 
				"redirect_uri=%s&" + 
				"response_type=code&" + 
				"client_id=%s";

		try {
			String scope =  URLEncoder.encode("email profile openid", "UTF-8");
			String callbackURI = URLEncoder.encode("http://localhost:8080/v1/auth/oauthcb", "UTF-8");
			String authURI = String.format(authURIPattern, scope, callbackURI, googleClientId);
			System.out.println(authURI);
			URI u = new URI(authURI);
			return Response.seeOther(u).build();
		} catch (URISyntaxException | UnsupportedEncodingException e) {
			// TODO won't happen
			e.printStackTrace();
			return Response.serverError().build();
		}
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
		ResponseBuilder response = Response.status(200).entity(user);
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
