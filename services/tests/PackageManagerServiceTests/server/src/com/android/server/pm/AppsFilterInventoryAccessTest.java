/*
 * Copyright (C) 2026 CharaROM
 * SPDX-License-Identifier: Apache-2.0
 */
package com.android.server.pm;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import android.os.UserHandle;
import android.util.ArraySet;
import android.util.Pair;

import com.android.server.pm.pkg.AndroidPackage;
import com.android.server.pm.pkg.PackageStateInternal;
import com.android.server.pm.pkg.PackageUserStateInternal;
import com.android.server.pm.pkg.SharedUserApi;

import org.junit.Before;
import org.junit.Test;

import java.util.List;

/** Tests the automatic catalog only, not explicit user-configured app-list restrictions. */
public class AppsFilterInventoryAccessTest {
    private static final int APP_ID = 10356;
    private static final String TARGET = "org.lineageos.recorder";
    private Computer mSnapshot;
    private PackageStateInternal mCaller;

    @Before
    public void setUp() {
        mSnapshot = mock(Computer.class);
        mCaller = caller(true, false, false);
        when(mSnapshot.getPackageOrSharedUser(APP_ID)).thenReturn(
                new Pair<>(mCaller, null));
    }

    private PackageStateInternal caller(boolean installed, boolean instant, boolean queryAll) {
        PackageStateInternal state = mock(PackageStateInternal.class);
        PackageUserStateInternal user = mock(PackageUserStateInternal.class);
        AndroidPackage pkg = mock(AndroidPackage.class);
        when(state.getPackageName()).thenReturn("test.inventory");
        when(state.getAndroidPackage()).thenReturn(pkg);
        when(state.getUserStateOrDefault(0)).thenReturn(user);
        when(user.isInstalled()).thenReturn(installed);
        when(user.isInstantApp()).thenReturn(instant);
        when(pkg.getRequestedPermissions()).thenReturn(queryAll
                ? List.of("android.permission.QUERY_ALL_PACKAGES") : List.of());
        return state;
    }

    private void useCaller(PackageStateInternal caller) {
        when(mSnapshot.getPackageOrSharedUser(APP_ID)).thenReturn(new Pair<>(caller, null));
    }

    @Test
    public void fullInventoryCanSeeRomAndRootCatalog() {
        useCaller(caller(true, false, true));
        assertFalse(AppsFilterBase.shouldHideFromUid(mSnapshot, APP_ID, TARGET));
        assertFalse(AppsFilterBase.shouldHideFromUid(
                mSnapshot, APP_ID, "com.topjohnwu.magisk"));
    }

    @Test
    public void ordinaryCallerStillFiltered() {
        assertTrue(AppsFilterBase.shouldHideFromUid(mSnapshot, APP_ID, TARGET));
    }

    @Test
    public void instantCallerDoesNotGetExemption() {
        useCaller(caller(true, true, true));
        assertTrue(AppsFilterBase.shouldHideFromUid(mSnapshot, APP_ID, TARGET));
    }

    @Test
    public void uninstalledCallerDoesNotGetExemption() {
        useCaller(caller(false, false, true));
        assertTrue(AppsFilterBase.shouldHideFromUid(mSnapshot, APP_ID, TARGET));
    }

    @Test
    public void unavailableManifestDoesNotGetExemption() {
        when(mCaller.getAndroidPackage()).thenReturn(null);
        assertTrue(AppsFilterBase.shouldHideFromUid(mSnapshot, APP_ID, TARGET));
    }

    @Test
    public void sharedUidUsesInstalledMemberInventoryAccess() {
        SharedUserApi shared = mock(SharedUserApi.class);
        ArraySet<PackageStateInternal> members = new ArraySet<>();
        members.add(mCaller);
        members.add(caller(true, false, true));
        when(shared.getPackageStates()).thenAnswer(invocation -> members);
        when(mSnapshot.getPackageOrSharedUser(APP_ID)).thenReturn(new Pair<>(null, shared));
        assertFalse(AppsFilterBase.shouldHideFromUid(mSnapshot, APP_ID, TARGET));
    }

    @Test
    public void sharedUidIgnoresUninstalledInventoryMember() {
        SharedUserApi shared = mock(SharedUserApi.class);
        ArraySet<PackageStateInternal> members = new ArraySet<>();
        members.add(mCaller);
        members.add(caller(false, false, true));
        when(shared.getPackageStates()).thenAnswer(invocation -> members);
        when(mSnapshot.getPackageOrSharedUser(APP_ID)).thenReturn(new Pair<>(null, shared));
        assertTrue(AppsFilterBase.shouldHideFromUid(mSnapshot, APP_ID, TARGET));
    }

    @Test
    public void secondaryUserUsesItsOwnInstallationState() {
        PackageStateInternal state = caller(true, false, true);
        PackageUserStateInternal secondary = mock(PackageUserStateInternal.class);
        when(state.getUserStateOrDefault(10)).thenReturn(secondary);
        useCaller(state);
        assertTrue(AppsFilterBase.shouldHideFromUid(
                mSnapshot, UserHandle.getUid(10, APP_ID), TARGET));
        when(secondary.isInstalled()).thenReturn(true);
        assertFalse(AppsFilterBase.shouldHideFromUid(
                mSnapshot, UserHandle.getUid(10, APP_ID), TARGET));
    }

    @Test
    public void nonCatalogPackagesUnaffected() {
        assertFalse(AppsFilterBase.shouldHideFromUid(mSnapshot, APP_ID, "test.ordinary"));
    }
}
