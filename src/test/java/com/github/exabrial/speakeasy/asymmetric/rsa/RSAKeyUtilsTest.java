/**
 * Copyright [2018] [Jonathan S. Fisher]
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package com.github.exabrial.speakeasy.asymmetric.rsa;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

public class RSAKeyUtilsTest {
	private final RSAKeyUtils rsaKeyUtils = new RSAKeyUtils();
	private final String publicKeyString = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmIMQ6UmDV3CcTDQH8nW9VEtSopEj6TAP/nuyx+DySyG4Dxn"
			+ "iv1dozWt0ajJXY2u5rCR8t0P33vuaR5iJ64BkRBv6KVTWjDu0r8QeYL+C29ejR01r4je+vL1qKr7bMCdsSZW85XQtkS1xMH2MIkKA44b9q4FiM3JAEuDrNy16774"
			+ "wnuKFmUHhcjVCjXA0VB3jGcms/QTI4ghrnh+J8S2lfnXvQPb/r72gJ4VAaSbZHs0FPU8+WzRnDL3NtBM+mTMIjdotgQ4wuoJLft4rnB0bV7lrWMARSlMX8PdHLhy"
			+ "n8YSgb46mxxt5icVgtR5ThKp7rzTMgZY1+dI3/4c/kOfbTQIDAQAB";
	private final String privateKeyString = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDcNeRsGZu+3KIurBR0OGP0BMGa0sGkb4+M1c0+t6"
			+ "ox6gPGSvc3Ut0b3DEM/a+8FpBwHUs0i9Xotkw6J2H4NhCmk7WqMF0EOIE2txUnwdf05Xs/NS/DvoSWcLhfZnvw0REZkNH1926fekGWxr2hmrpWGs4U+XtIQfWY3T"
			+ "8YM6JbSWyPTDa5BUhoOkTuseVwaPXggfq7F49cE4svurxQIlq2OIPLC7TqNGk5G4vi52rPwAHwig2/5R6iQOkqwx30oneoarj7w/f2VeBSD7IGlSQLHHHg51vl57"
			+ "ezOmYUmF+c2UtH9eVWtwj7zUrjtK7A5PZqOYQm6YHjZqQkYJDGWHJJAgMBAAECggEBAJ0JkavFV1v023ONI8j9rcoG2koeohkxtZ0pmwRu1eBike6G52V8olGL5S"
			+ "7uerQXI0nQmiEO16zs089k5mirpZQlIhgMBUlNQlhSl7OSeP8b55hbxYRCCSt/lvvxidFiRl+E9zYBDdKMzNlJQVJNlTRySSSMBW6yGwK4RJZtvAp8LpoITM87dX"
			+ "gsj8H0SEqv9tVvzoJyG+6KlOZvPr+ERA/Q9O/RA9fROXYFrS4QO9IlH7TnobN8bGjYkv2FpdNpb7+Rpimy5lK2CDI1QnLn09Hv1hxVQOHh2Hpa5hNq283zsmbGLw"
			+ "rGBenmMw+lsgZK2V7cfxt3o3YSa/AKbbVeWQECgYEA/clqiQ0R0GQ0dmnikqUwZRGzedpZiKNhYIxjCeNTKLKdecucMuofr9udxLY/0X+3YjaxKOX6lKx/gjVjmG"
			+ "e8Y+B6RsctXPnWO0Ti7ts1YsZI0I0zjIZRZ5zxVDanZjTSeTuSXUVr1BFeYsAXlPZngrdzRP7nmC9w9VRq6nr6G10CgYEA3iGENyO2GB3HL/vkY4n4fdkGOLyhds"
			+ "+fTgoffZWLx5hklnuAwMpqsXATc6HB7LvqM8jhnzQFiHDzpLZP0MjZcIsyO7fTQMXUmNL+uajR6iTRTrPIVVZ1ILGnod7mdijAnjHwmh3MeUa9oBDl6+OSk0ib1u"
			+ "hBXvq92Cpe1NU/790CgYBWOCx6fTc1HiX4qMZx3a8QVzArULQkSKVXgLpQ7Kse43e+nh7l6UZ0n179KpGJ4iLyOfR8GY3FHsl++hZo+600HVpNW3Oc58ARiLi0P0"
			+ "Lm2Mh6Gc6Oij9zvQz7+Els3rs2trdl+qTEelYfpHUehYvrC9occaFKwatVnaVpHfiEfQKBgQCtBMA+TrOcTz2CM5quqZ4DMFL3SH4f1BKKr7ndkOlCe4IF8IbWJB"
			+ "Q8x0Zvb9RkN+5xjYun/NY+c3RjnJnIz1kGn3VuLH4A2tcAfoBoToXK8giSW9i0F9a9s4MVw1ARQybdUZrOAF3vLNmw3tioByd5TzoLh/a7K2VKBZ69+qiFhQKBgE"
			+ "fPzf5+MSEnPV8/3CQYjhW+2DRIaZujiRHBUNH+EAyrghK8V8YbXpCUHLOESQ1BwZjBYh6h1/1Yt5CqCzcvce/meibK5cFF+E0XU62LXJSiRrgjtGPqFHg+EyJVS2"
			+ "CaXzMonx3dzBnL8UAvhyuZ1xJzApH8Hpz9JipL6HC3yRZf";

	@Test
	public void testCreateKeyPair() {
		final SpeakEasyRSAKeyPair createKeyPair = rsaKeyUtils.createKeyPair();
		assertEquals("RSA", createKeyPair.getPrivateKey().toJCEKey().getAlgorithm());
		assertEquals("RSA", createKeyPair.getPublicKey().toJCEKey().getAlgorithm());
	}

	@Test
	public void testReadPublicKey_ToStringSpeakEasyEccPublicKey() {
		final SpeakEasyRSAPublicKey readPublicKey = rsaKeyUtils.readPublicKey(publicKeyString);
		final String toKeyString = rsaKeyUtils.toString(readPublicKey);
		assertEquals(publicKeyString, toKeyString);
	}

	@Test
	public void testReadPrivateKey_ToStringSpeakEasyEccPrivateKey() {
		final SpeakEasyRSAPrivateKey readPrivateKey = rsaKeyUtils.readPrivateKey(privateKeyString);
		final String toKeyString = rsaKeyUtils.toString(readPrivateKey);
		assertEquals(privateKeyString, toKeyString);
	}
}
