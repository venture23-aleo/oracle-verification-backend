package common

import "github.com/venture23-aleo/oracle-verification-backend/constants"

// IsPriceFeedURL checks if the URL is a price feed URL.
func IsPriceFeedURL(url string) bool {
	return url == constants.PriceFeedBTCURL ||
		url == constants.PriceFeedETHURL ||
		url == constants.PriceFeedAleoURL || 
		url == constants.PriceFeedUSDTURL ||
		url == constants.PriceFeedUSDCURL
}

// ExtractAssetFromPriceFeedURL extracts the asset name from price feed URL
func ExtractTokenFromPriceFeedURL(url string) string {
	switch url {
	case constants.PriceFeedBTCURL:
		return "BTC"
	case constants.PriceFeedETHURL:
		return "ETH"
	case constants.PriceFeedAleoURL:
		return "ALEO"
	case constants.PriceFeedUSDTURL:
		return "USDT"
	case constants.PriceFeedUSDCURL:
		return "USDC"
	default:
		return "UNKNOWN"
	}
}

// GetTokenIDFromPriceFeedURL gets the token ID from price feed URL
func GetTokenIDFromPriceFeedURL(url string) int {
	switch url {
	case constants.PriceFeedBTCURL:
		return constants.BTCTokenID
	case constants.PriceFeedETHURL:
		return constants.ETHTokenID
	case constants.PriceFeedAleoURL:
		return constants.AleoTokenID
	case constants.PriceFeedUSDTURL:
		return constants.USDTTokenID
	case constants.PriceFeedUSDCURL:
		return constants.USDCTokenID
	default:
		return 0
	}
}