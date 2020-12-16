/*
 * Copyright 2020 The NATS Authors
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package jwt

import (
	"sort"
	"testing"
	"time"
)

func TestRevocationCompact(t *testing.T) {
	a := NewAccountClaims(publicKey(createAccountNKey(t), t))

	now := time.Now()
	var keys []string
	keys = append(keys, publicKey(createUserNKey(t), t))
	keys = append(keys, publicKey(createUserNKey(t), t))
	keys = append(keys, publicKey(createUserNKey(t), t))
	sort.Strings(keys)
	a.Revocations = make(RevocationList)
	a.Revocations.Revoke(keys[0], now.Add(-time.Hour))
	a.Revocations.Revoke(keys[1], now.Add(-time.Minute))
	a.Revocations.Revoke(keys[2], now.Add(-time.Second))
	// no change expected - there's no
	deleted := a.Revocations.MaybeCompact()
	if len(a.Revocations) != 3 || deleted != nil {
		t.Error("expected 3 revocations")
	}
	// should delete the first key
	a.Revocations.Revoke(All, now.Add(-time.Minute*30))
	deleted = a.Revocations.MaybeCompact()
	if len(a.Revocations) != 3 && len(deleted) != 1 && deleted[0].PublicKey != keys[0] {
		t.Error("expected 3 revocations")
	}
	// should delete the 2 remaining keys, only All remains
	a.Revocations.Revoke(All, now.Add(-time.Second))
	deleted = a.Revocations.MaybeCompact()
	if len(a.Revocations) != 1 && len(deleted) != 2 && deleted[0].PublicKey != keys[1] && deleted[1].PublicKey != keys[2] {
		t.Error("didn't revoke expected entries")
	}
}
