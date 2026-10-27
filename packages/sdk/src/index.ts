export {
  DemoApiClient,
  type DemoApiClientOptions,
} from "./clients/demo-api.js";
export {
  Ac2BridgeClient,
  type Ac2BridgeClientOptions,
  type OperatorAuthOption,
} from "./clients/ac2-bridge.js";
export {
  ConsoleClient,
  type ConsoleClientOptions,
  type ConsoleOperatorAction,
  type ConsoleOperatorChallenge,
  type ConsoleAuthOption,
} from "./clients/console.js";
export {
  HttpClient,
  MandateRailHttpError,
  type ClientOptions,
  type RequestOptions,
} from "./http.js";
export type {
  ApiError,
  HealthStatus,
  IntentMandate,
  IntentMandateCreate,
  Receipt,
  PairMode,
  PairStatus,
  SigningRequest,
  SignatureResult,
  PendingApproval,
  SignPendingResponse,
  RequestStatus,
  ApproveBody,
  ApproveResult,
  RejectResult,
  PaymentRequiredBody,
} from "./types.js";
export {
  OPERATOR_TOKEN_HEADER,
  OPERATOR_ATTESTATION_HEADER,
  REQUESTER_TOKEN_HEADER,
  API_KEY_HEADER,
  DEFAULT_DEMO_API_URL,
  DEFAULT_CONSOLE_URL,
  DEFAULT_AC2_BRIDGE_URL,
  TESTNET_DEMO_API_URL,
  TESTNET_AC2_BRIDGE_URL,
  TESTNET_CONSOLE_URL,
  TESTNET_SIGNDATA_DOMAIN,
  encodeOperatorAttestation,
  type OperatorAttestationEvidence,
  type OperatorChallenge,
} from "./types.js";
export {
  REQUESTER_AUTH_HEADER,
  REQUESTER_AUTH_PREFIX,
  buildRequesterMessage,
  signRequesterRequest,
  type RequesterSigner,
} from "./requester.js";
