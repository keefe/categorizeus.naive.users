package us.categorize.naive.api;

import us.categorize.api.Authorizer;
import us.categorize.api.UserStore;
import us.categorize.model.User;

public class NaiveAuthorizer implements Authorizer {
	
	private UserStore userStore; 
	
	public NaiveAuthorizer(UserStore userStore) {
		this.userStore = userStore;
	}
	
	@Override
	public boolean authorize(String sessionKey, String path, String method) {
		User user = userStore.getPrincipal(sessionKey);
		String userName = user!=null?user.getUsername():null;
		System.out.println("Current logged in user is " + userName);
		return true;
	}

}
