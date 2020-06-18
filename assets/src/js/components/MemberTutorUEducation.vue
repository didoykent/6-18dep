<template>
<v-container>
	<v-card class="font-weight-black ml-3 px-3" flat style="font-size:40px">
		<v-row align="center" class="subtitle-2 pa-6">
			<span @click="$router.push('/MemberTutor')" class="primary--text mr-2">TUTORS</span>
			>
			<span class="mx-2"> UEDUCATION </span>
			<v-spacer></v-spacer>
			<v-btn small color="primary" @click="$router.push('/MemberAddTutor')">Add New Tutor</v-btn>
		</v-row>
	</v-card>
	<v-row align-content="center" justify="center" align="center">
		<v-container>
			<v-row>
				<v-col cols="12" sm="12" md="6">
					<v-card class="display-2" max-height="300px" height="250px">
						<v-row align="end" justify="end" class="pa-2 mr-3 fill-height">
							AMBER
						</v-row>
					</v-card>
				</v-col>
				<v-col cols="12" sm="12" md="6">
					<v-card class="display-2" max-height="300px" height="250px">
						<v-row align="end" justify="end" class="pa-2 mr-3 fill-height">
							DIAMOND
						</v-row>
					</v-card>
				</v-col>
			</v-row>

			<v-row>
				<v-col cols="12" sm="12" md="6">
					<v-card class="display-2" max-height="300px" height="250px">
						<v-row align="end" justify="end" class="pa-2 mr-3 fill-height">
							EMERALD
						</v-row>
					</v-card>
				</v-col>
				<v-col cols="12" sm="12" md="6">
					<v-card class="display-2" max-height="300px" height="250px">
						<v-row align="end" justify="end" class="pa-2 mr-3 fill-height">
							ONYX
						</v-row>
					</v-card>
				</v-col>
			</v-row>
		</v-container>
	</v-row>

</v-container>
</template>

<script>
export default {

}
</script>

<style lang="css">
</style>
