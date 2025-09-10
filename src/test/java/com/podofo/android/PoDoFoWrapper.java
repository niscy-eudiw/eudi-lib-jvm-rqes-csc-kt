/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.podofo.android;

import java.util.List;
import java.util.logging.Logger;

/*
 * Test-specific version of PoDoFoWrapper that doesn't require native libraries.
 * This version provides mock functionality suitable for unit testing.
 */
public class PoDoFoWrapper {
    private final Logger logger = Logger.getLogger(PoDoFoWrapper.class.getName());
    private final String conformanceLevel;
    private final String hashAlgorithmOID;
    private final String documentInputPath;
    private final String documentOutputPath;
    private final String endEntityCertificate;
    private final String[] certificateChain;

    public PoDoFoWrapper(
            String conformanceLevel,
            String hashAlgorithmOID,
            String documentInputPath,
            String documentOutputPath,
            String endEntityCertificate,
            String[] certificateChain) {
        this.conformanceLevel = conformanceLevel;
        this.hashAlgorithmOID = hashAlgorithmOID;
        this.documentInputPath = documentInputPath;
        this.documentOutputPath = documentOutputPath;
        this.endEntityCertificate = endEntityCertificate;
        this.certificateChain = certificateChain;

        logger.info("PoDoFoWrapper: Test version initialized (no native libraries)");
    }

    public String calculateHash() {
        // Return mock hash for unit testing
        logger.info("PoDoFoWrapper: Returning mock hash for testing");
        return "MYIBAzAYBgkqhkiG9w0BCQMxCwYJKoZIhvc";
    }

    public void printState() {
        logger.info("PoDoFoWrapper: Mock state - document: " + documentInputPath);
    }

    public void finalizeSigningWithSignedHash(String signedHash, String base64Tsr, List<String> certs,
            List<String> crls, List<String> ocsps) {
        logger.info("PoDoFoWrapper: Mock finalization with hash: " + signedHash);
        logger.info("PoDoFoWrapper: Mock timestamp response: " + base64Tsr);
        logger.info("PoDoFoWrapper: Would create signed document at: " + documentOutputPath);
    }
}
