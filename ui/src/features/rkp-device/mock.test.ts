import { afterEach, describe, expect, it } from "vitest"

import mock from "./mock"

const originalUrl = location.href
afterEach(() => history.replaceState(null, "", originalUrl))

function provision(protocol?: string) {
  const flags: Record<string, string | true> = { "acknowledge-limitations": true }
  if (protocol !== undefined) flags.protocol = protocol
  return mock.handlers["rkp-device.provision"]!([], flags, undefined)
}

describe("device RKP mock protocol contract", () => {
  it.each([
    ["v1-only", "v2"],
    ["v1-only", "v1-native"],
    ["v2-only", "v1"],
  ])("rejects unavailable protocol %s/%s", (scenario, protocol) => {
    history.replaceState(null, "", `/?rkp=${scenario}`)
    expect(() => provision(protocol)).toThrowError(
      expect.objectContaining({ code: "unsupported_device" }),
    )
  })

  it("uses automatic selection when the CLI protocol flag is omitted", () => {
    history.replaceState(null, "", "/?rkp=v1-only")
    expect(provision()).toMatchObject({ csr_protocol: "v1", local_verify: null })
  })

  it("retains V2 preference when both protocols have resources", () => {
    history.replaceState(null, "", "/")
    expect(provision()).toMatchObject({
      csr_protocol: "v2",
      local_verify: { signature_valid: true },
    })
  })

  it("uses the native V1 backup only when explicitly selected", () => {
    history.replaceState(null, "", "/?rkp=v2-only")
    expect(provision("v1-native")).toMatchObject({
      csr_protocol: "v1",
      csr_backend: "native",
      local_verify: null,
    })
    expect(provision()).toMatchObject({ csr_protocol: "v2", csr_backend: "native" })
  })

  it("rejects invalid protocol flags as usage errors", () => {
    expect(() => provision("v3")).toThrowError(expect.objectContaining({ code: "usage_error" }))
  })

  it("requires acknowledgement before checking device prerequisites", () => {
    history.replaceState(null, "", "/?soc=unknown")
    expect(() => mock.handlers["rkp-device.provision"]!([], {}, undefined)).toThrowError(
      expect.objectContaining({ code: "acknowledgement_required" }),
    )
  })
})
