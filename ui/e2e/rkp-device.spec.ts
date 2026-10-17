import { expect, test } from "./fixtures"

test.beforeEach(async ({ page }) => {
  await page.addInitScript(() =>
    localStorage.setItem("duck-toolbox/acknowledged", JSON.stringify(["rkp-device"])),
  )
})

test("explicit V1 issuance reports structural verification", async ({ page, open }) => {
  await open("/rkp-device", { locale: "zh-CN" })
  await page.getByRole("combobox", { name: "协议" }).click()
  await page.getByRole("option", { name: "V1 AIDL", exact: true }).click()
  await page.getByRole("button", { name: "签发 RKP keybox", exact: true }).click()
  await page
    .getByRole("alertdialog")
    .getByRole("button", { name: "签发 RKP keybox", exact: true })
    .click()
  await expect(
    page.getByText("仅结构校验；加密签名材料由服务器验证", { exact: true }),
  ).toBeVisible()
  await expect(page.getByText("V1", { exact: true })).toBeVisible()
  await page.screenshot({ path: "test-results/rkp-device-v1-zh.png", fullPage: true })
})

test("automatic mode can issue on a V1-only device without V2 resources", async ({
  page,
  open,
}) => {
  await open("/rkp-device", { query: { rkp: "v1-only" } })
  await expect(page.getByRole("button", { name: "Issue RKP keybox", exact: true })).toBeEnabled()
  await page.getByRole("button", { name: "Issue RKP keybox", exact: true }).click()
  await page
    .getByRole("alertdialog")
    .getByRole("button", { name: "Issue RKP keybox", exact: true })
    .click()
  await expect(
    page.getByText("Structure checked; encrypted evidence is verified by the server", {
      exact: true,
    }),
  ).toBeVisible()
})

test("native V1 backup can be selected without an AIDL APK", async ({ page, open }) => {
  await open("/rkp-device", { query: { rkp: "v2-only" } })
  await page.getByRole("combobox", { name: "Protocol" }).click()
  await expect(page.getByRole("option", { name: "V1 AIDL", exact: true })).toBeDisabled()
  await page.getByRole("option", { name: "V1 Native (0x311e)", exact: true }).click()
  await page.getByRole("button", { name: "Issue RKP keybox", exact: true }).click()
  await page
    .getByRole("alertdialog")
    .getByRole("button", { name: "Issue RKP keybox", exact: true })
    .click()
  await expect(page.getByText("V1", { exact: true })).toBeVisible()
  await expect(page.getByText("Native", { exact: true })).toBeVisible()
  await expect(
    page.getByText("Structure checked; encrypted evidence is verified by the server", {
      exact: true,
    }),
  ).toBeVisible()
})

test("native V1 is disabled when the vendor resources are missing", async ({ page, open }) => {
  await open("/rkp-device", { query: { rkp: "v1-only" } })
  await page.getByRole("combobox", { name: "Protocol" }).click()
  await expect(page.getByRole("option", { name: "V1 Native (0x311e)", exact: true })).toBeDisabled()
})

test("automatic mode shows the failed attempts before native V1 success", async ({
  page,
  open,
}) => {
  await open("/rkp-device", { query: { rkp_fail: "v2,v1" } })
  await page.getByRole("button", { name: "Issue RKP keybox", exact: true }).click()
  await page
    .getByRole("alertdialog")
    .getByRole("button", { name: "Issue RKP keybox", exact: true })
    .click()
  await expect(page.getByRole("heading", { name: "Attempts", exact: true })).toBeVisible()
  await expect(
    page.getByText("[ta_rejected] v2 rejected the request", { exact: true }),
  ).toBeVisible()
  await expect(
    page.getByText("[ta_rejected] v1 rejected the request", { exact: true }),
  ).toBeVisible()
  await expect(page.getByText("Native", { exact: true })).toBeVisible()
})

test("automatic mode reports failure only after every method fails", async ({ page, open }) => {
  await open("/rkp-device")
  await page.getByRole("button", { name: "Issue RKP keybox", exact: true }).click()
  await page
    .getByRole("alertdialog")
    .getByRole("button", { name: "Issue RKP keybox", exact: true })
    .click()
  await expect(page.getByRole("heading", { name: "Result", exact: true })).toBeVisible()
  await page.evaluate(() => history.replaceState(null, "", "?rkp_fail=v2,v1,v1-native"))
  await page.getByRole("button", { name: "Issue RKP keybox", exact: true }).click()
  await page
    .getByRole("alertdialog")
    .getByRole("button", { name: "Issue RKP keybox", exact: true })
    .click()
  await expect(
    page.getByText("All available issuance methods failed. Review the errors for each attempt.", {
      exact: true,
    }),
  ).toBeVisible()
  await expect(page.getByRole("heading", { name: "Result", exact: true })).toHaveCount(0)
})

test("identifies QTI and keeps firmware compatibility unverified", async ({ page, open }) => {
  await open("/rkp-device", { locale: "zh-CN" })
  await expect(page.getByText("QTI", { exact: true }).first()).toBeVisible()
  await expect(page.getByText("已识别", { exact: true })).toBeVisible()
  await expect(page.getByText("尚未验证", { exact: true })).toBeVisible()
  await expect(page.getByRole("button", { name: "签发 RKP keybox", exact: true })).toBeEnabled()
  await expect(
    page.getByText("识别到了非高通 SoC 厂商；该操作需要高通 KeyMint。", { exact: true }),
  ).toHaveCount(0)
  await page.getByText("识别依据", { exact: true }).click()
  await expect(page.getByText("ro.soc.manufacturer", { exact: true })).toBeVisible()
  await page.screenshot({ path: "test-results/rkp-device-qti-zh.png", fullPage: true })
})

test("shows kernel fallback evidence when the vendor property is absent", async ({
  page,
  open,
}) => {
  await open("/rkp-device", { query: { soc: "fallback" } })
  await expect(page.getByText("Detected", { exact: true })).toBeVisible()
  await expect(page.getByRole("button", { name: "Issue RKP keybox", exact: true })).toBeEnabled()
  await page.getByText("Detection evidence", { exact: true }).click()
  await expect(page.getByText("/sys/devices/soc0/family", { exact: true })).toBeVisible()
  await expect(page.getByText("Snapdragon", { exact: true })).toBeVisible()
})

for (const [soc, message] of [
  [
    "unknown",
    "The SoC vendor could not be identified from local properties or kernel information.",
  ],
  ["conflict", "Local SoC information conflicts. Review the detection evidence before continuing."],
  ["other", "A non-Qualcomm SoC vendor was identified; this operation requires Qualcomm KeyMint."],
]) {
  test(`distinguishes ${soc} hardware and blocks issuance`, async ({ page, open }) => {
    await open("/rkp-device", { query: { soc: soc! } })
    await expect(page.getByText(message!, { exact: true })).toBeVisible()
    await expect(page.getByRole("button", { name: "Issue RKP keybox", exact: true })).toBeDisabled()
    if (soc !== "other")
      await expect(
        page.getByText(
          "A non-Qualcomm SoC vendor was identified; this operation requires Qualcomm KeyMint.",
          { exact: true },
        ),
      ).toHaveCount(0)
  })
}
