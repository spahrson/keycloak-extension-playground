package ch.puzzle.keycloak.oidc.mappers;

import org.jboss.logging.Logger;
import org.keycloak.common.util.RandomString;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.protocol.oidc.mappers.UserInfoTokenMapper;
import org.keycloak.protocol.oidc.mappers.UserPropertyMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.representations.IDToken;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class RandomStringOidcMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

    private static final String PROVIDER_ID = "oidc-randomstring-protocol-mapper";

    private static final Logger LOGGER = Logger.getLogger(RandomStringOidcMapper.class);

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES;

    private static final String CONFIG_PROPERTY_USER_ATTRIBUTE = "userAttribute";
    private static final String CONFIG_PROPERTY_RANDOM_STRING_LENGTH = "stringLength";
    private static final String CONFIG_PROPERTY_DEFAULT = "randomString";

    static {

        CONFIG_PROPERTIES = ProviderConfigurationBuilder.create()
                .property()
                .name(CONFIG_PROPERTY_USER_ATTRIBUTE)
                .type(ProviderConfigProperty.STRING_TYPE)
                .label("User Attribute Name for random string")
                .helpText("The User Attribute which is used to fetch/store random string.")
                .defaultValue(CONFIG_PROPERTY_DEFAULT)
                .add()

                .property()
                .name(CONFIG_PROPERTY_RANDOM_STRING_LENGTH)
                .type(ProviderConfigProperty.STRING_TYPE)
                .label("random string length")
                .helpText("Length for generated random string.")
                .defaultValue(32)
                .add()

              .build();

        OIDCAttributeMapperHelper.addAttributeConfig(CONFIG_PROPERTIES, UserPropertyMapper.class);
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getDisplayType() {
        return "Random String Mapper";
    }

    @Override
    public String getHelpText() {
        return "A oidc token mapper that generates a new random string if the corresponding user attribute not already exists.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession, KeycloakSession keycloakSession, ClientSessionContext clientSessionCtx) {

        String userAttribute = mappingModel.getConfig().getOrDefault(CONFIG_PROPERTY_USER_ATTRIBUTE, CONFIG_PROPERTY_DEFAULT);
        Integer randomStringLength = Integer.parseInt(mappingModel.getConfig().getOrDefault(CONFIG_PROPERTY_RANDOM_STRING_LENGTH, "32"));

        UserModel user = userSession.getUser();
        Map<String, List<String>> attributes = user.getAttributes();
        if(!attributes.containsKey(userAttribute)) {
            String randomString = new RandomString(randomStringLength).nextString();
            ArrayList<String> userAttributeValue = new ArrayList<>();
            userAttributeValue.add(randomString);
            userSession.getUser().setAttribute(userAttribute, userAttributeValue);
        }

        Object claimValue = user.getAttributes().get(userAttribute);
        LOGGER.infof("setClaim %s=%s", mappingModel.getName(), claimValue);

        OIDCAttributeMapperHelper.mapClaim(token, mappingModel, claimValue);
    }
}
