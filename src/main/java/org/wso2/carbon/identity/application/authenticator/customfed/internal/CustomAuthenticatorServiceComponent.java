package org.wso2.carbon.identity.application.authenticator.customfed.internal;

import java.util.Hashtable;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.test.bundle.ServiceAdapter;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.authenticator.customfed.CustomFedAuthenticator;

/**
 * @scr.component name="identity.application.authenticator.customfed.component"
 *                immediate="true"
 * @scr.reference name="test.bundle.serviceadapter"
 *                interface="org.test.bundle.ServiceAdapter"
 *                cardinality="1..1" policy="dynamic" bind="setServiceAdapter"
 *                unbind="unsetServiceAdapter"
 */
public class CustomAuthenticatorServiceComponent {

    private static final Log LOGGER = LogFactory.getLog(CustomAuthenticatorServiceComponent.class);

    private static ServiceAdapter serviceAdapter;

    protected void activate(ComponentContext ctxt) {
        try {
            CustomFedAuthenticator customFedAuthenticator = new CustomFedAuthenticator();
            Hashtable<String, String> props = new Hashtable<String, String>();
            ctxt.getBundleContext().registerService(ApplicationAuthenticator.class.getName(),customFedAuthenticator, props);
            LOGGER.info("----CustomFed Authenticator bundle is activated----");

        } catch (Throwable e) {
            LOGGER.fatal("----Error while activating CustomFed authenticator----", e);
        }
    }

    protected void deactivate(ComponentContext ctxt) {
        LOGGER.info("----CustomFed Authenticator bundle is deactivated----");
    }

    protected void setServiceAdapter(ServiceAdapter serviceAdapter){
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("serviceAdapter is set in the customAuthenticatorService bundle");
        }
        CustomAuthenticatorServiceComponent.serviceAdapter = serviceAdapter;
    }

    protected void unsetServiceAdapter(ServiceAdapter serviceAdapter){
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("serviceAdapter is unset in the customAuthenticatorService bundle");
        }
        CustomAuthenticatorServiceComponent.serviceAdapter = null;
    }

    public static ServiceAdapter getServiceAdapter(){
        return CustomAuthenticatorServiceComponent.serviceAdapter;
    }


}





