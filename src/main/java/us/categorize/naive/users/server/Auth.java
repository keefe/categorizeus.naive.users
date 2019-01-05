package us.categorize.naive.users.server;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import javax.ws.rs.Consumes;
import javax.ws.rs.CookieParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.NewCookie;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;

import org.apache.http.HttpEntity;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import us.categorize.Configuration;
import us.categorize.api.UserStore;
import us.categorize.model.User;

@Path("/auth")
public class Auth {
	protected UserStore userStore;
	private String googleClientId, googleClientSecret;
	private CloseableHttpClient client;
	private static String userAgentString = "us.categorize.naive.auth";
	private ObjectMapper mapper = new ObjectMapper();
	
	public Auth() {
		this.userStore = Configuration.instance().getUserStore();
		googleClientId = Configuration.instance().getGoogleClientId();
		googleClientSecret = Configuration.instance().getGoogleClientSecret();
		client = HttpClients.custom().setUserAgent(userAgentString).build();

	}
	
	@GET
	@Path("/oauthcb")
	public Response handleGoogleLogin(@CookieParam("categorizeus") Cookie cookie, 
			@QueryParam("code") String code,
			@QueryParam("error") String error) {
		System.out.println("Error " + error);
		System.out.println("Code " + code);
		try {
			HttpPost httpPost = new HttpPost("https://www.googleapis.com/oauth2/v4/token");
			List <NameValuePair> nvps = new ArrayList <NameValuePair>();
			nvps.add(new BasicNameValuePair("client_id", googleClientId));
			nvps.add(new BasicNameValuePair("client_secret", googleClientSecret));
			nvps.add(new BasicNameValuePair("redirect_uri", "http://localhost:8080/v1/auth/oauthcb"));
			nvps.add(new BasicNameValuePair("code", code));
			nvps.add(new BasicNameValuePair("grant_type", "authorization_code"));
			httpPost.setEntity(new UrlEncodedFormEntity(nvps));
			CloseableHttpResponse response2 = client.execute(httpPost);
		    HttpEntity entity = response2.getEntity();
	    	ObjectNode node = (ObjectNode) mapper.readTree(entity.getContent());
	    	String accessToken = node.get("access_token").asText();
	    	System.out.println("Access Token read as " + accessToken);
	    	HttpGet getProfile = new HttpGet("https://www.googleapis.com/oauth2/v2/userinfo");
	    	getProfile.setHeader("Authorization", "Bearer " + accessToken);
	    	getProfile.setHeader("Content-Type", "application/json");
			CloseableHttpResponse profileResponse = client.execute(getProfile);
			String profile = EntityUtils.toString(profileResponse.getEntity());
		    System.out.println(profile);
		    ObjectNode profileNode = (ObjectNode) mapper.readTree(profile);
		    User user = new User();
		    user.setEmail(profileNode.get("email").asText());
		    user.setUsername(profileNode.get("email").asText());
		    user.setGivenName(profileNode.get("given_name").asText());
		    user.setFamilyName(profileNode.get("family_name").asText());
		    user.setName(profileNode.get("name").asText());
		    user.setAuthorized(true);
		    userStore.registerUser(user);
			return Response.seeOther(new URI("http://localhost:8080")).build();
		} catch (URISyntaxException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ClientProtocolException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
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
