<template>
<div>

	<v-toolbar id="core-toolbar" flat prominent style="background: #eee;">


		<div class="v-toolbar-title">
			<v-toolbar-title style="font-size: 18px;" class="tertiary--text font-weight-light">
				<v-btn class="default v-btn--simple" dark icon>
					<v-icon>mdi-view-list</v-icon>
				</v-btn>
				Dashboard
			</v-toolbar-title>
		</div>

		<v-spacer />


	</v-toolbar>
    <router-view></router-view>

</div>
</template>

<script>
export default {

  // beforeMount(){
  //         this.$router.push('/MemberAddTutor')
  //   },

}
</script>

<style lang="css">
</style>
