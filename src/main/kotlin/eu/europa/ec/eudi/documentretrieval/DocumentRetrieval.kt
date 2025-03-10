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
package eu.europa.ec.eudi.documentretrieval

import eu.europa.ec.eudi.documentretrieval.internal.request.DefaultAuthorizationRequestResolver
import eu.europa.ec.eudi.documentretrieval.internal.response.DefaultDispatcher
import eu.europa.ec.eudi.rqes.DefaultHttpClientFactory
import eu.europa.ec.eudi.rqes.KtorHttpClientFactory

interface DocumentRetrieval : AuthorizationRequestResolver, Dispatcher {

    companion object {

        operator fun invoke(
            documentRetrievalConfig: DocumentRetrievalConfig,
            httpClientFactory: KtorHttpClientFactory = DefaultHttpClientFactory,
        ): DocumentRetrieval {
            val requestResolver = DefaultAuthorizationRequestResolver(documentRetrievalConfig, httpClientFactory)
            val dispatcher = DefaultDispatcher(httpClientFactory)
            return object :
                AuthorizationRequestResolver by requestResolver,
                Dispatcher by dispatcher,
                DocumentRetrieval {}
        }
    }
}
