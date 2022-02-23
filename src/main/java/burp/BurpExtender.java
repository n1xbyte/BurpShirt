package burp;

import app.BurpShirt;
import app.controllers.ContextMenuController;

import java.awt.*;


public class BurpExtender implements IBurpExtender, ITab {

    private static IBurpExtenderCallbacks extenderCallbacks;
    private static IExtensionHelpers helpers;
    private static BurpShirt burpShirt;

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        // Callback Objects
        BurpExtender.extenderCallbacks  = callbacks;
        BurpExtender.helpers = callbacks.getHelpers();

        // Extension Name
        callbacks.setExtensionName("BurpShirt");

        // Init
        burpShirt = new BurpShirt();

        // Add the UI
        callbacks.customizeUiComponent(burpShirt.getUI());

        // Add new tab
        callbacks.addSuiteTab(this);

        // Add right click menu
        ContextMenuController contextMenu = new ContextMenuController(burpShirt);
        callbacks.registerContextMenuFactory(contextMenu);
    }

    public static IBurpExtenderCallbacks getCallbacks() {
        return extenderCallbacks;
    }
    public static IExtensionHelpers getHelpers() {
        return helpers;
    }

    @Override
    public String getTabCaption() {
        return "BurpShirt";
    }

    @Override
    public Component getUiComponent() {
        return burpShirt.getUI();
    }

}
