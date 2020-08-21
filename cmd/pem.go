/*
Copyright © 2020 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"github.com/prasenjit-net/jwtconvert/pemc"

	"github.com/spf13/cobra"
)

// pemCmd represents the pem command
var pemCmd = &cobra.Command{
	Use:   "pem",
	Short: "Convert to pem format",
	Long:  `Converts a JWK key to PEM format`,
	Run:   pemc.ConvertToPEMFormat,
}

func init() {
	rootCmd.AddCommand(pemCmd)
	pemCmd.Flags().BoolP("no-verify", "k", false, "SSL no verify")
	_ = pemCmd.MarkPersistentFlagRequired("url")
}
