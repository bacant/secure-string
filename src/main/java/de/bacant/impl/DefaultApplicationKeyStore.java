package de.bacant.impl;

import com.sanguinecomputing.securestr.Long2Char;
import de.bacant.ApplicationKeyStore;

import java.lang.management.ManagementFactory;

public class DefaultApplicationKeyStore implements ApplicationKeyStore {
    @Override
    public char[] getGlobalApplicationPassword() {
        long jvmStartMillis = (ManagementFactory.getRuntimeMXBean().getStartTime());
        char[] result = Long2Char.convert(jvmStartMillis);
        return result;
    }
}
