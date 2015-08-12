package org.wso2.carbon.identity.application.authenticator.customfed;


import org.apache.axis2.context.ConfigurationContext;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.test.bundle.ServiceAdapter;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedIdPData;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.customfed.internal.CustomAuthenticatorServiceComponent;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.mgt.ApplicationConstants;
import org.wso2.carbon.user.api.ClaimManager;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.common.UserStore;
import org.wso2.carbon.utils.ConfigurationContextService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


public class CustomFedAuthenticator extends AbstractApplicationAuthenticator implements
                                                                             FederatedApplicationAuthenticator {

    private static final Log LOGGER = LogFactory.getLog(CustomFedAuthenticator.class);
    @Override
    protected void processAuthenticationResponse(HttpServletRequest httpServletRequest,
                                                 HttpServletResponse httpServletResponse,
                                                 AuthenticationContext authenticationContext)
            throws AuthenticationFailedException {


        //Check whether user is authenticated from previous step
        if(httpServletRequest.getAttribute("IsAuthenticated") != null && "false".equalsIgnoreCase(httpServletRequest.getAttribute("IsAuthenticated").toString())) {

            //Now the web service should be called and get the user authenticated
            /*
            Call the web service and get the results here isAuthenticated ? and claims
             */

            boolean authenticated = true;//Assign  the authentication step based on the webservice output
            if(!authenticated){
                //If the authentication failed throw InvalidCredentials exception
                throw new InvalidCredentialsException("Remote Service Call Authentication failed");
            }

            //Set the authenticated user name
            authenticationContext.setSubject("mario");

            //Creating set of hardcorded claims for testing , real values should be put based on the webservice output
            Map<ClaimMapping, String> claims = new HashMap<ClaimMapping, String>();
            claims.put(ClaimMapping.build("http://wso2.org/claims/lastname", "http://wso2.org/claims/lastname", null, true), "mario");
            claims.put(ClaimMapping.build("http://wso2.org/claims/givenname", "http://wso2.org/claims/givenname", null, true), "mariogiven");
            claims.put(ClaimMapping.build("http://wso2.org/claims/emailaddress", "http://wso2.org/claims/emailaddress", null, true), "mario@gmail.com");
            claims.put(ClaimMapping.build("http://wso2.org/claims/im", "http://wso2.org/claims/im", null, false), "marioId");
            //Setting the claims
            authenticationContext.setSubjectAttributes(claims);



        }else{
            //This section of code is called if the user exists in the primary user store
            try {
                //Retrieve the step map
                Map<Integer, StepConfig> data = authenticationContext.getSequenceConfig().getStepMap();

                ClaimManager claimManager = CarbonContext.getThreadLocalCarbonContext().getUserRealm().getClaimManager();
                Map<String,String> allLocalClaims = null;
                UserStoreManager userStore = CarbonContext.getThreadLocalCarbonContext().getUserRealm().getUserStoreManager();
                org.wso2.carbon.user.api.ClaimMapping[] claimMappings = claimManager
                        .getAllClaimMappings(ApplicationConstants.LOCAL_IDP_DEFAULT_CLAIM_DIALECT);

                List<String> localClaimURIs = new ArrayList<String>();
                for (org.wso2.carbon.user.api.ClaimMapping mapping : claimMappings) {
                    String claimURI = mapping.getClaim().getClaimUri();
                    localClaimURIs.add(claimURI);
                }
                //Retrieve all the claims from the user in the local user store
                allLocalClaims = userStore.getUserClaimValues(
                        MultitenantUtils.getTenantAwareUsername(data.get(1).getAuthenticatedUser()),
                        localClaimURIs.toArray(new String[localClaimURIs.size()]), null);
                //All the user attributes and subject identifier is set to this step  because it's configured in the local & outbound config of the SP
                authenticationContext.setSubjectAttributes(FrameworkUtils.buildClaimMappings(allLocalClaims));
                authenticationContext.setTenantDomain(data.get(1).getAuthenticatedUserTenantDomain());
                authenticationContext.setSubject(data.get(1).getAuthenticatedUser());

            } catch (UserStoreException e) {
                LOGGER.info("User store exception");
                throw new AuthenticationFailedException();
            }


        }

    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {
        super.initiateAuthenticationRequest(request, response, context);
    }

    @Override
    public boolean canHandle(HttpServletRequest request) {
        //We are not redirecting the use to any external page, therefore setting this attribute to null
        request.setAttribute(FrameworkConstants.REQ_ATTR_HANDLED, null);
        return true;
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {
            return "CustomFedAuth_Context_id";
    }

    @Override
    public String getName() {
        return "CustomFedAuthenticator";
    }

    @Override
    public String getFriendlyName() {
        return "customfed";
    }
}
